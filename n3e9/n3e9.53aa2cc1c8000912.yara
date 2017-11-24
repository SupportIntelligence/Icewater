
rule n3e9_53aa2cc1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53aa2cc1c8000912"
     cluster="n3e9.53aa2cc1c8000912"
     cluster_size="47"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys wbna"
     md5_hashes="['3a600e188abd50e2de5734e04ec9ac14','434639ede1d1e2e1cefe96bd89e40f3d','b6e75bfa27e05dd790f6a6e51290c928']"

   strings:
      $hex_string = { f7f3c6ffffceffffcededbbdcecfb5bdbaa5adae9cb5b29cdedfbdc6c7adc6c3adadae9ca5a69c9c9e948c8e847375736365634a4d4a424142313431292c2900 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
