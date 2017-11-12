
rule m3e9_6b2f25a4dd6b1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f25a4dd6b1b12"
     cluster="m3e9.6b2f25a4dd6b1b12"
     cluster_size="218"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['02f3491a5ac3230022774f9231ce5919','05abbc1e811c297313779feaebf2ff72','3f8b61d5845e501e60d623a2eee51d20']"

   strings:
      $hex_string = { 0f90bd918fefd6c2a89ce3a9abeb7b568e3085de9163c17a41bc4edda433a4bfbdd313954b85baad196d0b19befe8270d794c1b57f48dff7da5e4ff7d498de07 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
