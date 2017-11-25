
rule j3eb_3901580200000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3eb.3901580200000000"
     cluster="j3eb.3901580200000000"
     cluster_size="48"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="crypt kryptik malicious"
     md5_hashes="['25253fdf2038969c3378d27e1aaca637','269376e5c67a607eee465add744588e3','75c03f0a61a9c88715ad7acb2ef0dae3']"

   strings:
      $hex_string = { 21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000392411dd7d457f8e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
