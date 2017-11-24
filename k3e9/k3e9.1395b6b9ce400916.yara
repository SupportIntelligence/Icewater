
rule k3e9_1395b6b9ce400916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6b9ce400916"
     cluster="k3e9.1395b6b9ce400916"
     cluster_size="127"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor azbaukwkdpb backdoor"
     md5_hashes="['028095a03ec544bd4bcf60c496911624','0977f40e96fe631e183972588ca55be3','33eb75abde2309da7c61688395816ba5']"

   strings:
      $hex_string = { c85b5e5f5dc331c0b201f00fb053200f94c284d2749d8b731c8b431439c6720731c0864320eb8c8b431489c751c1e0026840d906005029f78b532452e8f2eafb }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
