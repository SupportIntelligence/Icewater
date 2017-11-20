
rule m3e9_5942dc62592ac6f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5942dc62592ac6f2"
     cluster="m3e9.5942dc62592ac6f2"
     cluster_size="460"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef autorun"
     md5_hashes="['0012d69df0b0630a86bb85f1c64668e9','00513598a78cebce7f6104c1c0a69d02','15cae8d6e11b0c1d97e9f3b3535d9d6b']"

   strings:
      $hex_string = { f3d19da0f3fdddae9fb1d4d5d0b1d27612000000000000000000000000000000000000001e7d7d512c306d8cbd72379cc0a85e3858ffc3995b97afb99e989b6b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
