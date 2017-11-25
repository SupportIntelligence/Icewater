
rule p3e9_519abb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.519abb49c8000b12"
     cluster="p3e9.519abb49c8000b12"
     cluster_size="90"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['0763bbc00ecd4f06f79c259b44844d16','12dee118e2633247105f22cf0e0532e0','a2b405b99adfc50bc21cb96fb9eec74c']"

   strings:
      $hex_string = { 7e0102020229e9b78fff9daef4ff2c54f1ff0938f2ff113ff3ff113ff3ff1f3afeff00b680ff00b767ff009e61ff008e55ff268c67ff84a398ffdac5b5fffae4 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
