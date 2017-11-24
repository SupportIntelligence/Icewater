
rule k2321_29156a8986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29156a8986220b32"
     cluster="k2321.29156a8986220b32"
     cluster_size="38"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['046b79cd8a61d514c41410ee84b04a0a','10324986212470ffa0d89d563e4fd39c','a3ed587cd976a1848ffdf3a6a954c124']"

   strings:
      $hex_string = { 169535da30e87c4524e7408e55003425b24451ca0427ff4672c35bfbaa3fb19749b0eaf3bc3d77f47e0af8f66aef4fbbeb320d311d1d1a3a5a4f4d3664940eb6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
