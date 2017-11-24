
rule m3e9_5999c538c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5999c538c8800b32"
     cluster="m3e9.5999c538c8800b32"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader chbm"
     md5_hashes="['05f7723ef001fe01176250031b6fd298','0728784f91451dd9df3c399865e8330d','ec8b21df7a8a3bb889082ac0d2e67b4f']"

   strings:
      $hex_string = { 188a038842288b45fc4783c004438945fc3bfe75ad5f5e5b8be55dc3e816e4ffff84c0753a33d28bc28bca83e03fc1f9066bc03003048df87e4100c64028c1c7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
