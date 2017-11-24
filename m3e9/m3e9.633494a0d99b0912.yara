
rule m3e9_633494a0d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.633494a0d99b0912"
     cluster="m3e9.633494a0d99b0912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['a5240ff376162abc7956a5ba3ab93f25','b25fdea38315059e110b17c7318189a1','fea14db9c3473097a60a9af8b0242fa8']"

   strings:
      $hex_string = { 195ea6c8561720dfd3bbd1edec13a0a26dd51f9840aaf4ae2dc9d865c0ae8e31f33050415f4e49937402f2c4add02abcbdd2291e48a10f2f76235aca9a11f551 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
