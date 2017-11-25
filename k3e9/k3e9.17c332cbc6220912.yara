
rule k3e9_17c332cbc6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17c332cbc6220912"
     cluster="k3e9.17c332cbc6220912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['1c84ca0a294d8fb4725a148b333709fa','bf1f16a9e54abdad273b99aec46cb3b5','deab2579d3dc7606058ef5e46861879d']"

   strings:
      $hex_string = { 33db395d1874238d85fcf7ffff50ff15d0100001592bf8578d8445fcf7ffff506a01ff3504320001ffd6391df83000015f5e75268b451cf7d81bc083e01083c0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
