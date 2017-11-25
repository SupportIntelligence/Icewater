
rule n3e9_0b14b4f9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b14b4f9c2200b16"
     cluster="n3e9.0b14b4f9c2200b16"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply generickd malicious"
     md5_hashes="['45f045e216a05e044abd5f01a19458e7','5de892dbbd757f696b11627cccc9e019','978799fb0653690df9608a93e320c42a']"

   strings:
      $hex_string = { 0043006f00640065003a002000250064002e000a00250073001b0041002000570069006e003300320020004100500049002000660075006e006300740069006f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
