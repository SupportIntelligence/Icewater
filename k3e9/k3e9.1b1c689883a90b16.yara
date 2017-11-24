
rule k3e9_1b1c689883a90b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c689883a90b16"
     cluster="k3e9.1b1c689883a90b16"
     cluster_size="660"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp delf"
     md5_hashes="['001d9f68f4e3ef1f9da7003008bec6e4','0061971a665abbe40fb60a5695e6b677','0773f1bc494ded022dca007191bd02b4']"

   strings:
      $hex_string = { 740650e8afdbffff83c42c5e5bc39053ba949140000fb60ae30a4231db43d3e339c37cf1915bc3558bec33c08b55088a52f280fa0273098b4d088079f3017516 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
