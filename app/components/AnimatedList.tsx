'use client';

import React, { ReactNode } from 'react';
import AnimateTransition from './AnimateTransition';

interface AnimatedListProps {
  items: ReactNode[];
  visible: boolean;
  animationType?: 'slide-left' | 'slide-right' | 'slide-up' | 'slide-down' | 'scale-up';
  staggerDelay?: number;
  className?: string;
  itemClassName?: string;
}

const AnimatedList = ({
  items,
  visible,
  animationType = 'slide-up',
  staggerDelay = 100,
  className = '',
  itemClassName = '',
}: AnimatedListProps) => {
  return (
    <div className={className}>
      {items.map((item, index) => (
        <AnimateTransition
          key={index}
          show={visible}
          type={animationType}
          delay={index * staggerDelay}
          className={itemClassName}
        >
          {item}
        </AnimateTransition>
      ))}
    </div>
  );
};

export default AnimatedList;
