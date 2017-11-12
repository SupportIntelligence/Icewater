
rule n3e9_2db2190cea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2db2190cea210932"
     cluster="n3e9.2db2190cea210932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['1207bcb7fa33446296af05a0e65303d1','699b25c2a058ed98af49314bd7e3a1e4','7abbb0776ac60eedf54a5d7295790b42']"

   strings:
      $hex_string = { da035006600651059004700680069006d0056402a00651059004b006c006d006d004e006a006510590042006f0064006d005640200071007f002200730074007 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
