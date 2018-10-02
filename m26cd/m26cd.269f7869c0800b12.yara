
rule m26cd_269f7869c0800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26cd.269f7869c0800b12"
     cluster="m26cd.269f7869c0800b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gafgyt linux backdoor"
     md5_hashes="['85ced26bb4e65a8f1d63296a4115fc190b50fe37','5a2daa1e4914818722f43ffed65523b11d6e0578','68e24a12e82fc2d53a4d060a7f1fe6c87c12c7e7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26cd.269f7869c0800b12"

   strings:
      $hex_string = { 340a8d8800c0ffffc1e91083e102d3e089c2c1e80ff7d0c1ea0e21c28d040e29c28d4a13d3ef83e7038d54975489d0c34157ba80175100be969b400041564155 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
