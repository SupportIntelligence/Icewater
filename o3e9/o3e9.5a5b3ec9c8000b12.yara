
rule o3e9_5a5b3ec9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5a5b3ec9c8000b12"
     cluster="o3e9.5a5b3ec9c8000b12"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock yvxwmroi nabucur"
     md5_hashes="['02d6982b5d8b1d85d4d9ca388832e461','043c83de5b000d624a9ccfb339df5d1b','da4bb024d09ea14f1ad870c088f2dd81']"

   strings:
      $hex_string = { 1c3dd0ff2149dbff2754e5ff2a5cedff2b5deeff2856e8ff234cdeff1d40d3ff7b6386fffee3c8fffcd1beffdd978bff331a0d8c351b0e3c3f1b1b0e7f7f7f01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
