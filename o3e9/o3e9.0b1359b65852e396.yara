
rule o3e9_0b1359b65852e396
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b1359b65852e396"
     cluster="o3e9.0b1359b65852e396"
     cluster_size="840"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr dlboost installmonster"
     md5_hashes="['0013265248ce80a6e8d2b861c068fc09','0047e6aa3e02c041ae996689325ba978','0657ad019a6f9248e2b145c02ce7fb62']"

   strings:
      $hex_string = { 7acf3a478b1ba1eb6e4755af9201047104d8c0771e3a152367477f62dac7bc6fb2c0d1c03809394a84e18e6807076d085143d53995bef80f89320294f9dd87e5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
