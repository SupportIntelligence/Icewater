
rule k3e9_1395b6bace400916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6bace400916"
     cluster="k3e9.1395b6bace400916"
     cluster_size="4087"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor rzzbaukwkdpb"
     md5_hashes="['002c9effdb983cb812af7ed07e2add06','0032df7556eccaff347cba14e0c2b6b6','01b4875c75acec2ecb7f2f1baefe4e17']"

   strings:
      $hex_string = { c85b5e5f5dc331c0b201f00fb053200f94c284d2749d8b731c8b431439c6720731c0864320eb8c8b431489c751c1e0026840d906005029f78b532452e8f2eafb }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
