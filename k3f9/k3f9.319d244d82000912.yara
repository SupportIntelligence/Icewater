
rule k3f9_319d244d82000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.319d244d82000912"
     cluster="k3f9.319d244d82000912"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack selfdel generickdz"
     md5_hashes="['0d496ded1b565b72c8dec46a6c863583','a3d473a2a7686f619b8e99516ba39310','ebe6117898bc3e00fbbcb10906bd843a']"

   strings:
      $hex_string = { 06092fb4c2114a0486ab5d10ce209a0fda230090f0ebdf2be4d1019164c777d55bc10b416064d70f6189c9be4fd8493142361adc3332212744cb157aea7e951d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
