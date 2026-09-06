<script lang="ts">
	interface ChartSeries {
		label: string;
		values: (number | null)[];
		tone: 'accent' | 'ink' | 'muted';
		dashed?: boolean;
	}

	export let series: ChartSeries[] = [];
	export let timestamps: number[];
	export let unit: string;
	export let label = 'Telemetry';
	export let zeroBased = true;
	export let height = 148;
	export let maxValue: number | null = null;
	export let formatValue: (value: number) => string = (value) => value.toLocaleString(undefined, { maximumFractionDigits: 1 });
	export let emptyMessage = 'Waiting for telemetry samples.';

	const width = 640;
	const inset = 8;
	const timeFormat = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

	$: values = series.flatMap((item) => item.values.filter((value, index): value is number => value !== null && Number.isFinite(value) && Number.isFinite(timestamps[index])));
	$: sampleTimes = timestamps.filter((timestamp, index) => Number.isFinite(timestamp) && series.some((item) => item.values[index] != null && Number.isFinite(item.values[index])));
	$: start = sampleTimes.length ? Math.min(...sampleTimes) : 0;
	$: end = sampleTimes.length ? Math.max(...sampleTimes) : 0;
	$: minimum = zeroBased || values.length === 0 ? 0 : Math.min(...values);
	$: maximum = Math.max(minimum + 1, maxValue ?? (values.length ? Math.max(...values) : 1));
	$: range = maximum - minimum;
	$: ticks = [maximum, minimum + range / 2, minimum];
	$: plotted = series.map((item) => ({ ...item, ...geometry(item.values, timestamps, start, end, minimum, range, height) }));

	function geometry(input: (number | null)[], times: number[], start: number, end: number, minimum: number, range: number, height: number) {
		let path = '';
		let connected = false;
		let latest: { x: number; y: number } | null = null;
		for (let index = 0; index < input.length; index++) {
			const value = input[index];
			if (value === null || !Number.isFinite(value) || !Number.isFinite(times[index])) {
				connected = false;
				latest = null;
				continue;
			}
			const x = start === end ? width / 2 : inset + ((times[index] - start) / (end - start)) * (width - inset * 2);
			const y = height - inset - ((value - minimum) / range) * (height - inset * 2);
			path += `${connected ? ' L' : ' M'} ${x.toFixed(2)} ${y.toFixed(2)}`;
			connected = true;
			latest = { x, y };
		}
		return { path, latest };
	}
</script>

{#if values.length === 0}
	<p class="chart-empty">{emptyMessage}</p>
{:else}
	<figure class="chart">
		<div class="unit">{unit}</div>
		<div class="plot" style:height={`${height}px`}>
			<div class="scale" aria-hidden="true">
				{#each ticks as tick}<span>{formatValue(tick)}</span>{/each}
			</div>
			<svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={`${label}; ${formatValue(minimum)} to ${formatValue(maximum)} ${unit}`}>
				{#each [0, 0.5, 1] as ratio}
					<line x1={inset} y1={inset + (height - inset * 2) * ratio} x2={width - inset} y2={inset + (height - inset * 2) * ratio} class="gridline" />
				{/each}
				{#each plotted as item}
					{#if item.path}
						<path d={item.path} class:tone-accent={item.tone === 'accent'} class:tone-ink={item.tone === 'ink'} class:tone-muted={item.tone === 'muted'} class:dashed={item.dashed} />
						{#if item.latest}
							<circle cx={item.latest.x} cy={item.latest.y} r="3.5" class:tone-accent={item.tone === 'accent'} class:tone-ink={item.tone === 'ink'} class:tone-muted={item.tone === 'muted'} />
						{/if}
					{/if}
				{/each}
			</svg>
		</div>
		<figcaption>
			<div class="time-scale">
				<time datetime={new Date(start).toISOString()} title={new Date(start).toLocaleString()}>{timeFormat.format(start)}</time>
				<time datetime={new Date(end).toISOString()} title={new Date(end).toLocaleString()}>{timeFormat.format(end)}</time>
			</div>
			<span>{sampleTimes.length} {sampleTimes.length === 1 ? 'sample' : 'samples'} · {((end - start) / 1000).toLocaleString(undefined, { maximumFractionDigits: 1 })} s sampled · local time</span>
		</figcaption>
	</figure>
{/if}

<style>
	.chart {
		min-width: 0;
		margin: 0;
	}

	.unit,
	figcaption {
		color: var(--color-muted);
		font-size: var(--text-xs);
	}

	.unit {
		margin-bottom: var(--space-1);
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
		padding: 0 var(--space-2) 0 0;
		color: var(--color-muted);
		font-size: var(--text-xs);
		text-align: right;
		font-variant-numeric: tabular-nums;
	}

	svg {
		display: block;
		flex: 1;
		min-width: 0;
		height: 100%;
	}

	figcaption {
		display: grid;
		gap: var(--space-1);
		margin-top: var(--space-2);
	}

	.time-scale {
		display: flex;
		justify-content: space-between;
		gap: var(--space-2);
		font-variant-numeric: tabular-nums;
	}

	.chart-empty {
		margin: 0;
		padding: var(--space-5) var(--space-3);
		border-block: var(--rule-thin) solid var(--color-rule);
		color: var(--color-muted);
		font-size: var(--text-sm);
	}

	.gridline {
		stroke: var(--color-rule);
		stroke-width: 1;
		vector-effect: non-scaling-stroke;
	}

	path {
		fill: none;
		stroke-width: 2;
		stroke-linecap: square;
		stroke-linejoin: bevel;
		vector-effect: non-scaling-stroke;
	}

	circle {
		stroke: var(--color-paper);
		stroke-width: 2;
		vector-effect: non-scaling-stroke;
	}

	path.tone-accent { stroke: var(--color-accent); }
	path.tone-ink { stroke: var(--color-ink); }
	path.tone-muted { stroke: var(--color-muted); }
	circle.tone-accent { fill: var(--color-accent); }
	circle.tone-ink { fill: var(--color-ink); }
	circle.tone-muted { fill: var(--color-muted); }
	.dashed { stroke-dasharray: 5 4; }
</style>
