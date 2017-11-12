
rule k3e9_4b4626a4ce564c5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ce564c5a"
     cluster="k3e9.4b4626a4ce564c5a"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['020a20d6771465b2a83f34340c841ba9','0575a44cbc49c4f620b311d3c3f4fbb3','e1cd45ae66b39a90a5de27d4e95ed8be']"

   strings:
      $hex_string = { 03d58b6e1003fd8906895e04894e0889560c897e105d5b5f5ec20800cccccccc568b74241085f6762b8b4c24088b44240c4183c0028a50018851ff8a1088118a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
