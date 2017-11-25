
rule n3e9_2db2199dee210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2db2199dee210932"
     cluster="n3e9.2db2199dee210932"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['0aa50f6cfdf442eb98301ad91598767b','0e4e284ca6ba5da53454ff6ef757d59a','db114a18b591be9971f6b311a67a9d80']"

   strings:
      $hex_string = { da035006600651059004700680069006d0056402a00651059004b006c006d006d004e006a006510590042006f0064006d005640200071007f002200730074007 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
