
rule k3f4_21525cd982200b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.21525cd982200b10"
     cluster="k3f4.21525cd982200b10"
     cluster_size="4239"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="linkury zusy toolbar"
     md5_hashes="['0002adeaec4cf07de71e3c8f44e9258d','000407074497e832cda8db7ba8a24a40','0143592b85081f3882dc37ab8800769c']"

   strings:
      $hex_string = { 6c6c54657874005370656369616c466f6c64657200476574466f6c646572506174680047657452616e646f6d46696c654e616d6500436f6d62696e6500436f70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
