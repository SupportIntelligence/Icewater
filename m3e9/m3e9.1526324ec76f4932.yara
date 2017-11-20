
rule m3e9_1526324ec76f4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1526324ec76f4932"
     cluster="m3e9.1526324ec76f4932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex blpei"
     md5_hashes="['2dce19c5197650baa9abd7afaec5e1a2','bb96fe5f421f3c4568cde510a90d9699','db8e41a48827cb6b3046b3b0c13b963f']"

   strings:
      $hex_string = { 69071d150a3c3b3b2c273d1f2c3b3a20262700090077270518130214033e1300290089dac6cfdddec8dbccd5c4e0eafbe6fae6effdd5dee0e7ede6fefad5cafc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
