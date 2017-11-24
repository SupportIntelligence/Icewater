
rule k2377_4a9e97c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4a9e97c9c8000b12"
     cluster="k2377.4a9e97c9c8000b12"
     cluster_size="14"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe blackhole exploit"
     md5_hashes="['3c282e67e0d67525e58a92d58c037bba','4f534b94624a0a54e79de8da6d0be7e4','bc35f5a7dfd3f1682583ad59225faff1']"

   strings:
      $hex_string = { 67653d224a617661536372697074223e0d0a203c212d2d0d0a207334756578743d733475706c28293b0d0a20646f63756d656e742e777269746528273c696d67 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
