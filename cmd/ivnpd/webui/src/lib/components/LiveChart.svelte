<script lang="ts">
	interface ChartSeries {
		label: string;
		values: number[];
		tone: 'accent' | 'ink' | 'muted';
		dashed?: boolean;
	}

	export let series: ChartSeries[] = [];
	export let label = 'Live telemetry';
	export let zeroBased = true;
	export let height = 148;

	const width = 640;
	const inset = 8;

	$: values = series.flatMap((item) => item.values).filter(Number.isFinite);
	$: minimum = zeroBased || values.length === 0 ? 0 : Math.min(...values);
	$: maximum = values.length === 0 ? 1 : Math.max(...values);
	$: range = Math.max(1, maximum - minimum);

	function pathFor(input: number[]): string {
		if (input.length === 0) return '';
		return input
			.map((value, index) => {
				const x = input.length === 1 ? width - inset : inset + (index / (input.length - 1)) * (width - inset * 2);
				const y = height - inset - ((value - minimum) / range) * (height - inset * 2);
				return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
			})
			.join(' ');
	}

	function latestPoint(input: number[]): { x: number; y: number } | null {
		if (input.length === 0) return null;
		return {
			x: width - inset,
			y: height - inset - ((input[input.length - 1] - minimum) / range) * (height - inset * 2)
		};
	}
</script>

<div class="chart" class:compact={height <= 118} class:tall={height >= 160}>
	<svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={label}>
		{#each [0.25, 0.5, 0.75] as ratio}
			<line x1={inset} y1={height * ratio} x2={width - inset} y2={height * ratio} class="gridline" />
		{/each}
		{#each series as item}
			{@const path = pathFor(item.values)}
			{@const latest = latestPoint(item.values)}
			{#if path}
				<path
					d={path}
					class:tone-accent={item.tone === 'accent'}
					class:tone-ink={item.tone === 'ink'}
					class:tone-muted={item.tone === 'muted'}
					class:dashed={item.dashed}
				/>
				{#if latest}
					<circle
						cx={latest.x}
						cy={latest.y}
						r="3.5"
						class:tone-accent={item.tone === 'accent'}
						class:tone-ink={item.tone === 'ink'}
						class:tone-muted={item.tone === 'muted'}
					/>
				{/if}
			{/if}
		{/each}
	</svg>
</div>

<style>
	.chart {
		width: 100%;
		height: 8.5rem;
		min-height: 5.75rem;
		border-block: var(--rule-thin) solid var(--color-rule);
		background: var(--color-paper-2);
	}

	.chart.compact {
		height: 6.75rem;
	}

	.chart.tall {
		height: 11rem;
	}

	svg {
		display: block;
		width: 100%;
		height: 100%;
		overflow: visible;
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

	path.tone-accent {
		stroke: var(--color-accent);
	}

	path.tone-ink {
		stroke: var(--color-ink);
	}

	path.tone-muted {
		stroke: var(--color-muted);
	}

	circle.tone-accent {
		fill: var(--color-accent);
	}

	circle.tone-ink {
		fill: var(--color-ink);
	}

	circle.tone-muted {
		fill: var(--color-muted);
	}

	.dashed {
		stroke-dasharray: 5 4;
	}
</style>
