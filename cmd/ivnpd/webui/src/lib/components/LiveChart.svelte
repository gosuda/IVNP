<script lang="ts">
	interface ChartSeries {
		label: string;
		values: (number | null)[];
		tone: 'accent' | 'ink' | 'muted';
		dashed?: boolean;
	}

	let {
		series,
		times,
		label,
		height = 160,
		zeroBased = true,
		maxValue = null,
		formatValue = (value: number) => value.toLocaleString(undefined, { maximumFractionDigits: 1 }),
		emptyMessage = 'Waiting for samples.'
	}: {
		series: ChartSeries[];
		times: number[];
		label: string;
		height?: number;
		zeroBased?: boolean;
		maxValue?: number | null;
		formatValue?: (value: number) => string;
		emptyMessage?: string;
	} = $props();

	const inset = 6;
	const clock = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
	const clockSeconds = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

	let width = $state(0);
	let hover = $state<number | null>(null);

	const finite = (value: number | null | undefined): value is number => value !== null && value !== undefined && Number.isFinite(value);
	const values = $derived(series.flatMap((item) => item.values.filter(finite)));
	const start = $derived(times.length ? times[0] : 0);
	const end = $derived(times.length ? times[times.length - 1] : 0);
	const minimum = $derived(zeroBased || values.length === 0 ? 0 : Math.min(...values));
	const maximum = $derived(Math.max(minimum + 1, maxValue ?? (values.length ? Math.max(...values) * 1.08 : 1)));
	const x = (time: number) => (start === end ? width / 2 : inset + ((time - start) / (end - start)) * Math.max(width - inset * 2, 1));
	const y = (value: number) => height - inset - ((value - minimum) / (maximum - minimum)) * (height - inset * 2);

	const paths = $derived(
		series.map((item) => {
			let d = '';
			let pen = false;
			let last: { x: number; y: number } | null = null;
			item.values.forEach((value, index) => {
				if (!finite(value) || !finite(times[index])) {
					pen = false;
					return;
				}
				const point = { x: x(times[index]), y: y(value) };
				d += `${pen ? 'L' : 'M'}${point.x.toFixed(1)} ${point.y.toFixed(1)}`;
				pen = true;
				last = point;
			});
			return { ...item, d, last: last as { x: number; y: number } | null };
		})
	);

	function pointerMove(event: PointerEvent): void {
		if (times.length === 0) return;
		const bounds = (event.currentTarget as SVGElement).getBoundingClientRect();
		const offset = event.clientX - bounds.left;
		let nearest = 0;
		for (let index = 1; index < times.length; index++) {
			if (Math.abs(x(times[index]) - offset) < Math.abs(x(times[nearest]) - offset)) nearest = index;
		}
		hover = nearest;
	}

	const latestSummary = $derived(
		series
			.map((item) => {
				const latest = item.values.findLast(finite);
				return `${item.label} ${latest === undefined ? 'no data' : formatValue(latest)}`;
			})
			.join(', ')
	);
</script>

{#if values.length === 0}
	<p class="chart-empty">{emptyMessage}</p>
{:else}
	<figure class="chart">
		<div class="legend">
			{#each series as item (item.label)}
				<span><i class={item.tone} class:dashed={item.dashed}></i>{item.label}</span>
			{/each}
		</div>
		<div class="plot">
			<div class="scale" aria-hidden="true">
				<span>{formatValue(maximum)}</span>
				<span>{formatValue(minimum + (maximum - minimum) / 2)}</span>
				<span>{formatValue(minimum)}</span>
			</div>
			<div class="canvas" bind:clientWidth={width} style:height={`${height}px`}>
				{#if width > 0}
					<svg
						width={width}
						{height}
						viewBox={`0 0 ${width} ${height}`}
						role="img"
						aria-label={`${label}. Latest: ${latestSummary}.`}
						onpointermove={pointerMove}
						onpointerleave={() => (hover = null)}
					>
						{#each [0, 0.5, 1] as ratio (ratio)}
							<line class="grid" x1={inset} x2={width - inset} y1={inset + (height - inset * 2) * ratio} y2={inset + (height - inset * 2) * ratio} />
						{/each}
						{#each paths as item (item.label)}
							<path d={item.d} class={item.tone} class:dashed={item.dashed} />
							{#if item.last && hover === null}
								<circle cx={item.last.x} cy={item.last.y} r="3.5" class={item.tone} />
							{/if}
						{/each}
						{#if hover !== null}
							<line class="cursor" x1={x(times[hover])} x2={x(times[hover])} y1={inset} y2={height - inset} />
							{#each paths as item (item.label)}
								{#if finite(item.values[hover])}
									<circle cx={x(times[hover])} cy={y(item.values[hover] as number)} r="3.5" class={item.tone} />
								{/if}
							{/each}
						{/if}
					</svg>
					{#if hover !== null}
						<div class="readout" style:left={`${Math.min(Math.max(x(times[hover]), 70), width - 70)}px`}>
							<time datetime={new Date(times[hover]).toISOString()}>{clockSeconds.format(times[hover])}</time>
							{#each series as item (item.label)}
								<span>{item.label}: <strong>{finite(item.values[hover]) ? formatValue(item.values[hover] as number) : '—'}</strong></span>
							{/each}
						</div>
					{/if}
				{/if}
			</div>
		</div>
		<figcaption>
			<time datetime={new Date(start).toISOString()}>{clock.format(start)}</time>
			<span>{Math.max(1, Math.round((end - start) / 60_000))} min window</span>
			<time datetime={new Date(end).toISOString()}>{clock.format(end)}</time>
		</figcaption>
	</figure>
{/if}

<style>
	.chart {
		display: grid;
		gap: var(--space-2);
		min-width: 0;
		margin: 0;
	}

	.legend {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-4);
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.legend span {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
	}

	.legend i {
		display: block;
		width: 1rem;
		height: 0;
		border-top: var(--rule-heavy) solid var(--color-ink);
	}

	.legend i.accent {
		border-top-color: var(--color-accent);
	}

	.legend i.muted {
		border-top-color: var(--color-muted);
	}

	.legend i.dashed {
		border-top-style: dashed;
	}

	.plot {
		display: flex;
		min-width: 0;
		border-block: var(--rule-thin) solid var(--color-rule);
		background: var(--color-paper-2);
	}

	.scale {
		display: flex;
		flex-direction: column;
		justify-content: space-between;
		flex: 0 0 auto;
		min-width: 4.5rem;
		padding: 0 var(--space-2);
		color: var(--color-muted);
		font-size: var(--text-xs);
		text-align: right;
	}

	.canvas {
		position: relative;
		flex: 1;
		min-width: 0;
	}

	svg {
		display: block;
		touch-action: none;
	}

	.grid {
		stroke: var(--color-rule);
		stroke-width: 1;
	}

	.cursor {
		stroke: var(--color-rule-strong);
		stroke-width: 1;
	}

	path {
		fill: none;
		stroke-width: 2;
		stroke-linejoin: round;
	}

	path.accent {
		stroke: var(--color-accent);
	}

	path.ink {
		stroke: var(--color-ink);
	}

	path.muted {
		stroke: var(--color-muted);
	}

	path.dashed {
		stroke-dasharray: 5 4;
	}

	circle {
		stroke: var(--color-paper);
		stroke-width: 2;
	}

	circle.accent {
		fill: var(--color-accent);
	}

	circle.ink {
		fill: var(--color-ink);
	}

	circle.muted {
		fill: var(--color-muted);
	}

	.readout {
		position: absolute;
		top: var(--space-1);
		display: grid;
		gap: 2px;
		padding: var(--space-2);
		border: var(--rule-thin) solid var(--color-ink);
		background: var(--color-paper);
		box-shadow: 4px 4px 0 var(--color-shadow);
		font-size: var(--text-xs);
		white-space: nowrap;
		transform: translateX(-50%);
		pointer-events: none;
	}

	figcaption {
		display: flex;
		justify-content: space-between;
		gap: var(--space-2);
		padding-left: 4.5rem;
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.chart-empty {
		padding: var(--space-6) var(--space-3);
		border-block: var(--rule-thin) solid var(--color-rule);
		color: var(--color-muted);
		font-size: var(--text-sm);
	}
</style>
