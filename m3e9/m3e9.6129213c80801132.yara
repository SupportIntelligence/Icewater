
rule m3e9_6129213c80801132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6129213c80801132"
     cluster="m3e9.6129213c80801132"
     cluster_size="515043"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['0000afa4af0f7679a165a11b528615b1','000159005684d64172114ef8d8a4036b','000515f819982e605957dfa36fc27585']"

   strings:
      $hex_string = { 4c7a59adf5d4a62cfb9757c4cabb416f7eb252bdc7f39ae1da1c01b84b8df039288ee2fbaac34b32bce50d352d5aa099d7de94a502c2f80c344f8905dd2ac16a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
