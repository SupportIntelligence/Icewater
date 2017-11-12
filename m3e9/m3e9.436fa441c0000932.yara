
rule m3e9_436fa441c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.436fa441c0000932"
     cluster="m3e9.436fa441c0000932"
     cluster_size="116"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik malicious"
     md5_hashes="['000b1d002e726277ec18629f6b38a154','13cda7ba4c1b93ac6e3c32a4d8838061','5b56a5fce248f0cbea5cfa3771f6b9db']"

   strings:
      $hex_string = { 90de4000c38bff565733f6bf98de4000833cf53cc3400001751d8d04f538c34000893868a00f0000ff3083c718ff15d080400085c0740c4683fe247cd333c040 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
