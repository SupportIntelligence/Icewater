
rule k3e9_092b311e5ae28912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092b311e5ae28912"
     cluster="k3e9.092b311e5ae28912"
     cluster_size="211"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jeefo hidrag flood"
     md5_hashes="['09169d77eb2768bc2b2d6f69636708b0','0a486eb4ea0f88c3806bc3e0257e7d1b','3a13715b15a7514e97fbdf727df8ebd9']"

   strings:
      $hex_string = { 379f39a23bb03d3e3fe94162439145af47ab49bc4bbb4dc14fbf51b853c85576579b59c95bce5dce5fcf61d463c565da67d169d96bda6d9c6f9071b373e075e2 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
