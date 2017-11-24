
rule m2377_63b1008cdae30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.63b1008cdae30932"
     cluster="m2377.63b1008cdae30932"
     cluster_size="80"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00a78c6bc242d427d9c7aed19fcefe0c','05b0260f9fc254c3a4e0a6eae4420c1e','3849533545febd9df18b69d8c5cb08d0']"

   strings:
      $hex_string = { 42364337453939353641333746414530344344303941453232384437443436314237314235423246383238393833364438354543344441354638334632333031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
