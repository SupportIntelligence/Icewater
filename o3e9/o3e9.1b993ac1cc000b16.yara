
rule o3e9_1b993ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1b993ac1cc000b16"
     cluster="o3e9.1b993ac1cc000b16"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['39cc5fe21f47f3acf8825c8ba8c9d6b7','bfac84b9e528fa0773b3e68eb21ce38e','d147694d5ae3f4800c158f7e20fb409f']"

   strings:
      $hex_string = { 7e0102020229e9b78fff9daef4ff2c54f1ff0938f2ff113ff3ff113ff3ff1f3afeff00b680ff00b767ff009e61ff008e55ff268c67ff84a398ffdac5b5fffae4 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
