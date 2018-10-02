
rule n26bb_4b1a16e1c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a16e1c6000b12"
     cluster="n26bb.4b1a16e1c6000b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply filerepmetagen attribute"
     md5_hashes="['71582ba48dcafb60c89ca1edd740de6280d5b091','e05f50f4c42ed533c4e74feff4dbfe7aba725cbd','0879aacbd00476addd8f74700c7f5e1ea4fe93a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a16e1c6000b12"

   strings:
      $hex_string = { de203934b82f044279ffcfc4da37d02f57cc64ffe81466bfd9f707506f699272005bfcef4361562ab3f9dd6bf6055f00ef18111005cad76dee36341df1017f3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
