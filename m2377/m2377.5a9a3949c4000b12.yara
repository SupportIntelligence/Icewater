
rule m2377_5a9a3949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.5a9a3949c4000b12"
     cluster="m2377.5a9a3949c4000b12"
     cluster_size="23"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2315e5847b9aa7bd44b2db9857792e23','3d690bbac46724b68866aa49f6b85069','af64c1dadc4d1b58aa4d0e6b1605bbec']"

   strings:
      $hex_string = { 8d9a5bc6647b9d90e489cbabcd9500ead95e80af3882093f397abc78a32d790771c17d944263fea47e568de8a5b4884fddfff891de0d2f746dcec924588c6223 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
