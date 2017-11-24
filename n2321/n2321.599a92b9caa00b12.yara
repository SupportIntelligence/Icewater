
rule n2321_599a92b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.599a92b9caa00b12"
     cluster="n2321.599a92b9caa00b12"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0fef1f685b356538c0e4ef186891cd85','318e27212c47abaffa3e4aa065b3428d','f8ad64639a8ddca29e493cb321d9c76c']"

   strings:
      $hex_string = { 4e4ae3a062cd270728704fd0297c95ee3ac5f381858c83a3db9d15be9e7df27e7a8bc300e7674314b41d91926b20185821bb1b8fc4dce65048bf8d22a8b07bad }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
