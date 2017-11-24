
rule m3e9_0a38954315b84166
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0a38954315b84166"
     cluster="m3e9.0a38954315b84166"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['04913c7eaa508cc99c626ada18a8203b','10681f33f1cab14729b3d95281c27e37','ae164f2e879432192f5a1c60b0133145']"

   strings:
      $hex_string = { 21eaebd02404f92ca3282e6b208fbaa79ce4d42910a841e1cc132dedb8694d64a2d70551e3d29979b285ca9b1adbc963782a19390834af466183e07584c6936d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
