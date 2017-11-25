
rule m3e9_613494a2d3bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.613494a2d3bb0912"
     cluster="m3e9.613494a2d3bb0912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['90cb7bcefe8b869c7c5bfd3e8a829e7d','9bf100f54618c100bdce7fe37f548dd1','b6f4ee2d0fb7c684b5655b08b564806d']"

   strings:
      $hex_string = { 91ea3dc38bcb208e83dc398f83d17badeadf7998d88f79f1b58617ebcdf76180c88b6c94cd896195d58c59aaed9754e181b43bcec0cc21d993fc13cf8c9e74ec }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
