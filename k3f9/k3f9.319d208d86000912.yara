
rule k3f9_319d208d86000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.319d208d86000912"
     cluster="k3f9.319d208d86000912"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack generickdz selfdel"
     md5_hashes="['10eed36e38f546d22d3b99c690290b93','15b881e4e6ca614011f6733432d37da5','d72cd8ba46f11ac8c177b35d71307a0c']"

   strings:
      $hex_string = { 06092fb4c2114a0486ab5d10ce209a0fda230090f0ebdf2be4d1019164c777d55bc10b416064d70f6189c9be4fd8493142361adc3332212744cb157aea7e951d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
