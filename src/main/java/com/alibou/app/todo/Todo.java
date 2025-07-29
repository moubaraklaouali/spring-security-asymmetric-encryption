package com.alibou.app.todo;

import com.alibou.app.category.Category;
import com.alibou.app.common.BaseEntity;
import com.alibou.app.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;
import java.time.LocalTime;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@Table(name = "TODOS")
public class Todo extends BaseEntity {

    @Column(name = "TITLE", nullable = false)
    private String title;
    @Column(name = "DESCRIPTION", nullable = false)
    private String description;
    @Column(name = "SATRT_DATE", nullable = false)
    private LocalDate startDate;
    @Column(name = "END_DATE", nullable = false)
    private LocalDate endDate;
    @Column(name = "START_TIME", nullable = false)
    private LocalTime startTime;
    @Column(name = "END_TIME", nullable = false)
    private LocalTime endTime;
    @Column(name = "IS_DONE", nullable = false)
    private boolean done;
    @ManyToOne
    @JoinColumn(name = "OWNER_ID")
    private User user;
    @ManyToOne
    @JoinColumn(name = "CATEGORY_ID")
    private Category category;

}
