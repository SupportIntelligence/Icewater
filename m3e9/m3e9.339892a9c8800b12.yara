
rule m3e9_339892a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.339892a9c8800b12"
     cluster="m3e9.339892a9c8800b12"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator rstdbjki gain"
     md5_hashes="['11d5b5381817ef2603d8812046197174','17e8dc65eb023983df85131953e4addf','ffeeb597c9a8f56253a8bfaa2c8dc518']"

   strings:
      $hex_string = { ca2c92afbf9e4901d911dccd26416814cbbcfcf62a6971a1b95ede6b98c0b19383a8ebb433e3324d2e26880fe42790c40c531ee739b8288bdb7d70897663ab67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
