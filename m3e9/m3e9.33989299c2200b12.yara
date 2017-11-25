
rule m3e9_33989299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33989299c2200b12"
     cluster="m3e9.33989299c2200b12"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator rstdbjki gain"
     md5_hashes="['31c0b5c14f4309e5deec9e05ba9f11bf','321f01b51a03eb90eb2637a26999c4cf','e693fb1e3e7760ecd5af5fc354c91afe']"

   strings:
      $hex_string = { ca2c92afbf9e4901d911dccd26416814cbbcfcf62a6971a1b95ede6b98c0b19383a8ebb433e3324d2e26880fe42790c40c531ee739b8288bdb7d70897663ab67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
