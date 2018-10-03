
rule n26bb_2116dad6da63d912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2116dad6da63d912"
     cluster="n26bb.2116dad6da63d912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="remoteadmin ammyy malicious"
     md5_hashes="['c50c73a80bdaf8c7562571a8ab1725321c581dd6','132381295af182544c399ac2bd1b380185694d8c','f7260e6df84ac1e96fd72a7e1adc652f35108985']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2116dad6da63d912"

   strings:
      $hex_string = { 508b45e0ff7004ff1530564800b8e30f4100c3515356578bf98d4f10894c240ce8209d0100a1001c4b006a0333d259f7f133f68bd885db7e2c5533edb9f41b4b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
