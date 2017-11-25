
rule n3e9_2db18e42d96b6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2db18e42d96b6b32"
     cluster="n3e9.2db18e42d96b6b32"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy dealply malicious"
     md5_hashes="['05e5c1ee96b095927304f5829f6fbddc','107a80870cfadd91d85d51c24fd6492d','e1b492126be4967c81c680824b2cced2']"

   strings:
      $hex_string = { da035006600651059004700680069006d0056402a00651059004b006c006d006d004e006a006510590042006f0064006d005640200071007f002200730074007 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
