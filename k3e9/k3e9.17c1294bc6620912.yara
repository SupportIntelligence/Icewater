
rule k3e9_17c1294bc6620912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17c1294bc6620912"
     cluster="k3e9.17c1294bc6620912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['65b494c788cf6298f5fb93f507c44da9','bd1b8ec8ff787fafec26a89ce61169de','e6606e87b98ee102a9227e6cc3374eae']"

   strings:
      $hex_string = { 33db395d1874238d85fcf7ffff50ff15d0100001592bf8578d8445fcf7ffff506a01ff3504320001ffd6391df83000015f5e75268b451cf7d81bc083e01083c0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
