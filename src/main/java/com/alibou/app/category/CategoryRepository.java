package com.alibou.app.category;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface CategoryRepository extends JpaRepository<Category, String> {
    @Query("""
            SELECT COUNT (c) > 0
            FROM Category c
            WHERE LOWER(c.name) = LOWER(:name)
            AND c.createdBy = :userId OR c.createdBy = 'APP'
            """)
    boolean findByNameAndUser(String name, String userId);

    @Query("""
            SELECT c FROM Category c
            WHERE c.createdBy = :userId OR c.createdBy = 'APP'
            """)
    List<Category> findAllByUserId(String userId);

    @Query("""
            SELECT c FROM Category c
            WHERE c.id = :categoryId
            AND (c.createdBy = :userId OR c.createdBy = 'APP')
            """)
    Optional<Category> findByIdAndUserId(String categoryId, String userId);
}
