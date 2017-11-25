
rule o3e9_69553ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.69553ec9c4000b32"
     cluster="o3e9.69553ec9c4000b32"
     cluster_size="28"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['0396939a827838b76a550226add37f5b','049f64a348dd4fa0f02ab7f2cebc3c39','baf30115db5f38dcbb3ba56a3e4715e6']"

   strings:
      $hex_string = { 1c3dd0ff2149dbff2754e5ff2a5cedff2b5deeff2856e8ff234cdeff1d40d3ff7b6386fffee3c8fffcd1beffdd978bff331a0d8c351b0e3c3f1b1b0e7f7f7f01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
