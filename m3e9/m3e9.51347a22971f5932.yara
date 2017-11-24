
rule m3e9_51347a22971f5932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.51347a22971f5932"
     cluster="m3e9.51347a22971f5932"
     cluster_size="109"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef jorik"
     md5_hashes="['02417aa04d58d4264cb58df778bf4330','04025d3887117f5e40452ccc1e1a0421','72064e0a6a6ac978e7219f1b4bfdd10c']"

   strings:
      $hex_string = { f08d55e08d45e452506a02ff15781040008d4dd08d55c051526a02ff156010400083c418663bf774068b450c668938897dfc687c704200eb318d4de8ff15d412 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
