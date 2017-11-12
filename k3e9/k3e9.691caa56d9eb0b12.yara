
rule k3e9_691caa56d9eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.691caa56d9eb0b12"
     cluster="k3e9.691caa56d9eb0b12"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre waski generickd"
     md5_hashes="['044b1d955967adb473546bf04112168c','13b02604f9c38ce87d7bf8f010990805','c9294730cd8a95bc18a170d401f2fefe']"

   strings:
      $hex_string = { 0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
