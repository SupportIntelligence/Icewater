
rule o3e9_59593ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.59593ec9c4000b32"
     cluster="o3e9.59593ec9c4000b32"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock ypadjiei nabucur"
     md5_hashes="['0d12f50b8abd770837f29c0340455d40','14404126c3aec0d5474fd6dbbfc6c8ab','a1739aa3a86671528bb515d31deb041d']"

   strings:
      $hex_string = { 1c3dd0ff2149dbff2754e5ff2a5cedff2b5deeff2856e8ff234cdeff1d40d3ff7b6386fffee3c8fffcd1beffdd978bff331a0d8c351b0e3c3f1b1b0e7f7f7f01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
