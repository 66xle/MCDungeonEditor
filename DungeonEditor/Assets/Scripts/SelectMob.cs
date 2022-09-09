using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEditor;

public class SelectMob : MonoBehaviour
{
    public enum Mob
    {
        Zombie, Husk, Drowned, 
        Skeleton, Stray, WitherSkeleton,
        Spider, CaveSpider,
        Hoglin, Zoglin,
        Piglin, PiglinBrute, ZombiePiglin,
        Slime, MagmaCube,
        Pillager, Vindicator, Illusioner, Evoker,
        Ravager, Blaze, Witch,
    }
    [Space]
    
    public Mob mob;

    public Mob previous;

}

[CustomEditor(typeof(SelectMob))]
public class SelectMobEditor : Editor
{
    public override void OnInspectorGUI()
    {
        SelectMob script = (SelectMob)target;

        script.mob = (SelectMob.Mob)EditorGUILayout.EnumPopup("Mob Selected", script.mob);
        
        EditorGUILayout.Space();

        if (script.mob != script.previous)
        {
            script.previous = script.mob;

            switch (script.mob)
            {
                case SelectMob.Mob.Zombie:
                    ChangeMob(script, "Mobs/Zombie/zombie.geo");
                    break;
                case SelectMob.Mob.Husk:
                    ChangeMob(script, "Mobs/Husk/husk.geo");
                    break;
                case SelectMob.Mob.Drowned:
                    ChangeMob(script, "Mobs/Drowned/drowned.geo");
                    break;

                case SelectMob.Mob.Skeleton:
                    ChangeMob(script, "Mobs/Skeleton/skeleton.geo");
                    break;
                case SelectMob.Mob.Stray:
                    ChangeMob(script, "Mobs/Stray/stray.geo");
                    break;
                case SelectMob.Mob.WitherSkeleton:
                    ChangeMob(script, "Mobs/Wither Skeleton/witherskeleton.geo");
                    break;

                case SelectMob.Mob.Spider:
                    ChangeMob(script, "Mobs/Spider/spider.geo");
                    break;
                case SelectMob.Mob.CaveSpider:
                    ChangeMob(script, "Mobs/Cave Spider/cavespider.geo");
                    break;

                case SelectMob.Mob.Hoglin:
                    ChangeMob(script, "Mobs/Hoglin/hoglin.geo");
                    break;
                case SelectMob.Mob.Zoglin:
                    ChangeMob(script, "Mobs/Zoglin/zoglin.geo");
                    break;

                case SelectMob.Mob.Piglin:
                    ChangeMob(script, "Mobs/Piglin/piglin.geo");
                    break;
                case SelectMob.Mob.PiglinBrute:
                    ChangeMob(script, "Mobs/Piglin Brute/piglinbrute.geo");
                    break;
                case SelectMob.Mob.ZombiePiglin:
                    ChangeMob(script, "Mobs/Zombie Piglin/zombiepiglin.geo");
                    break;

                case SelectMob.Mob.Slime:
                    ChangeMob(script, "Mobs/Slime/slime.geo");
                    break;
                case SelectMob.Mob.MagmaCube:
                    ChangeMob(script, "Mobs/Magma Cube/magmacube.geo");
                    break;

                case SelectMob.Mob.Pillager:
                    ChangeMob(script, "Mobs/Pillager/pillager.geo");
                    break;
                case SelectMob.Mob.Vindicator:
                    ChangeMob(script, "Mobs/Vindicator/vindicator.geo");
                    break;
                case SelectMob.Mob.Illusioner:
                    ChangeMob(script, "Mobs/Illusioner/illusioner.geo");
                    break;
                case SelectMob.Mob.Evoker:
                    ChangeMob(script, "Mobs/Evoker/evoker.geo");
                    break;

                case SelectMob.Mob.Ravager:
                    ChangeMob(script, "Mobs/Ravager/ravager.geo");
                    break;
                case SelectMob.Mob.Blaze:
                    ChangeMob(script, "Mobs/Blaze/blaze.geo");
                    break;
                case SelectMob.Mob.Witch:
                    ChangeMob(script, "Mobs/Witch/witch.geo");
                    break;
            }
        }

        serializedObject.ApplyModifiedProperties();
    }

    void ChangeMob(SelectMob script, string path)
    {
        if (script.transform.childCount == 0)
        {
            GameObject obj = Resources.Load(path) as GameObject;
            GameObject mobObj = Instantiate(obj);
            mobObj.transform.SetParent(script.transform);
            mobObj.transform.localPosition = Vector3.zero;
            mobObj.transform.rotation = script.transform.localRotation;
        }
        else
        {
            Transform child = script.transform.GetChild(0);
            
            DestroyImmediate(child.gameObject);

            GameObject obj = Resources.Load(path) as GameObject;
            GameObject mobObj = Instantiate(obj);
            mobObj.transform.SetParent(script.transform);
            mobObj.transform.localPosition = Vector3.zero;
            mobObj.transform.rotation = script.transform.localRotation;
        }
    }

}

