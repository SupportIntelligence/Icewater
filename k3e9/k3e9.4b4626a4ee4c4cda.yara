
rule k3e9_4b4626a4ee4c4cda
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee4c4cda"
     cluster="k3e9.4b4626a4ee4c4cda"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['264d9cd4c58a44e7a447a8204cba8a53','51deaddd2b0eba115dd3dca45730eaef','ffb324712666d8eeacd2bea9e56409f8']"

   strings:
      $hex_string = { 0c03d58b6e1003fd8906895e04894e0889560c897e105d5b5f5ec20800cccccccc568b74241085f6762b8b4c24088b44240c4183c0028a50018851ff8a108811 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
