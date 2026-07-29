import type { PerformanceMetrics } from '../types';

/**
 * Performance monitoring utilities
 */

export interface PerformanceMonitor {
	startOperation(operation: string, inputSize: number): PerformanceTracker;
}

export interface PerformanceTracker {
	readonly operation: string;
	readonly startTime: number;
	end(
		outputSize: number,
		itemCount: number,
		errors: number,
		warnings: number,
	): PerformanceMetrics;
}

/**
 * Create a performance monitor
 */
export function createPerformanceMonitor(): PerformanceMonitor {
	return Object.freeze({
		startOperation(operation: string, inputSize: number): PerformanceTracker {
			const startTime = performance.now();
			const startMemory = process.memoryUsage().heapUsed;
			const startCpu = process.cpuUsage();

			return Object.freeze({
				operation,
				startTime,
				end(
					outputSize: number,
					itemCount: number,
					errors: number,
					warnings: number,
				): PerformanceMetrics {
					const endTime = performance.now();
					const duration = endTime - startTime;
					const memoryUsage = process.memoryUsage().heapUsed - startMemory;
					const cpuUsage = process.cpuUsage(startCpu);
					const totalCpuUsage = cpuUsage.user + cpuUsage.system;

					return Object.freeze({
						operation,
						startTime,
						endTime,
						duration,
						inputSize,
						outputSize,
						itemCount,
						memoryUsage,
						cpuUsage: totalCpuUsage,
						warnings,
						errors,
					});
				},
			});
		},
	});
}
