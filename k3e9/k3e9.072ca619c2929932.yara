
rule k3e9_072ca619c2929932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.072ca619c2929932"
     cluster="k3e9.072ca619c2929932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor berbew peed"
     md5_hashes="['05ce800209b916ae3bf95402f59a0290','1c6ba397531de3079d3d5bc240cb92d5','d124bb5b6ef25778a524c31cd51e1b82']"

   strings:
      $hex_string = { 73734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e45786563 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
