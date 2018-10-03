
rule m26bb_110d6944d88a4dea
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.110d6944d88a4dea"
     cluster="m26bb.110d6944d88a4dea"
     cluster_size="173"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz gandcrab malicious"
     md5_hashes="['9889d75af03a3fe26e77ae7ccf3b8b375dea5671','a97bc8119c09f8841189f9201747abd3d655597a','f7393ac52c0c34105dda30b8110519f34d6b3dbe']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.110d6944d88a4dea"

   strings:
      $hex_string = { ac7bb59466e170125d8cbf13bcda8df15b48edcbce937939fadfe92e1db97d534f86a56d742baf01247fa9503b7eb181b8a209ec455806eb40233e4055b3e20e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
