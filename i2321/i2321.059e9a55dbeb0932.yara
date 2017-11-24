
rule i2321_059e9a55dbeb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.059e9a55dbeb0932"
     cluster="i2321.059e9a55dbeb0932"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['45107076a6e950fcf41c6673906ab41a','5c0d562a64687ecf47d39171772eb83d','eb1d0b109aa483302e2c92403a86f9a4']"

   strings:
      $hex_string = { 255b4ed6ac78247bd42757b6ff4248f6680fd56aad63f54fc923d9eeafcc9eb543d7679f8af856d81e17b30d31dbeaecea5369eb8ed96fc7063e543d97df8d4d }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
